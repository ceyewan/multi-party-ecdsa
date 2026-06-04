use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt, TryStreamExt};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

mod gg20_sm_client;
use gg20_sm_client::join_computation_with_index;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
    #[structopt(short, long)]
    local_share: PathBuf,
    #[structopt(short, long)]
    index: u16,

    #[structopt(short, long, use_delimiter(true))]
    parties: Vec<u16>,
    #[structopt(short, long)]
    data_to_sign: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
    let number_of_parties = args.parties.len();

    let (i, incoming, outgoing) = join_computation_with_index(
        args.address.clone(),
        &format!("{}-offline", args.room),
        args.index,
    )
    .await
    .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (_i, incoming, outgoing) =
        join_computation_with_index(args.address, &format!("{}-online", args.room), args.index)
            .await
            .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let data_to_sign = parse_data_to_sign(&args.data_to_sign)?;
    let (signing, partial_signature) = SignManual::new(data_to_sign, completed_offline_stage)?;

    outgoing
        .send(Msg {
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    println!("{}", signature);

    Ok(())
}

fn parse_data_to_sign(data: &str) -> Result<BigInt> {
    let trimmed = data.trim();
    let hex_text = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if trimmed.starts_with("0x") || (hex_text.len() == 64 && is_hex(hex_text)) {
        if hex_text.len() % 2 != 0 {
            return Err(anyhow!(
                "hex data-to-sign must have an even number of characters"
            ));
        }
        let bytes = hex::decode(hex_text).context("decode hex data-to-sign")?;
        return Ok(BigInt::from_bytes(&bytes));
    }
    Ok(BigInt::from_bytes(trimmed.as_bytes()))
}

fn is_hex(value: &str) -> bool {
    value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}
