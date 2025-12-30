use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter},
    path::PathBuf,
};

use clap::Parser;
use mimalloc::MiMalloc;
use network2::{Id, Participant, TcpTree};
use rand::RngCore;

const ITER_COUNT: u32 = 10;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    id: Id,
    #[arg(short, long)]
    party_count: Option<usize>,
    #[arg(short, long)]
    config_path: Option<PathBuf>,
    #[arg(short, long)]
    base_port: Option<u16>,
    #[arg(short, long)]
    suffix: Option<String>,
    #[arg(long)]
    scheme: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let id = args.id;

    let suffix = if let Some(suffix) = args.suffix {
        suffix
    } else {
        String::from("tree")
    };

    let base_port = args.base_port.unwrap_or(12367);

    let mut data = Vec::new();

    let (parties, chunk_sizes) = if let Some(path) = args.config_path {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let parties = Participant::from_reader(&mut reader, base_port)?;

        let mut line = String::new();
        reader.read_line(&mut line)?;

        if let Some(scheme) = args.scheme
            && scheme == "qelect"
        {
            (parties, [1024 * 1024, 1024 * 1024])
        } else {
            let mut iter = line.split_whitespace().map(|s| s.parse::<usize>());

            let a = iter.next().unwrap()?;
            let b = iter.next().unwrap()?;

            (parties, [a * 1024, b * 1024])
        }
    } else {
        let party_count = args.party_count.unwrap();
        if let Some(scheme) = args.scheme
            && scheme == "qelect"
        {
            (
                Participant::from_default(party_count, base_port),
                [1024 * 1024, 1024 * 1024],
            )
        } else {
            (
                Participant::from_default(party_count, base_port),
                [600 * 1024, 200 * 1024],
            )
        }
    };

    let party_count = parties.len();

    // println!("Party {id}: {parties:?}");

    let tcp_tree = TcpTree::new(id, parties).await?;

    let mut result = [0.0; 2];

    for (i, chunk_size) in chunk_sizes.into_iter().enumerate() {
        data.resize(chunk_size * party_count, 0);

        data.chunks_exact_mut(chunk_size)
            .skip(id as usize)
            .take(1)
            .for_each(|part| {
                let mut rng = rand::rng();
                rng.fill_bytes(part);
            });

        tcp_tree.share(&mut data, chunk_size).await?;

        let start_time = quanta::Instant::now();

        for _j in 0..ITER_COUNT {
            tcp_tree.share(&mut data, chunk_size).await?;
            // println!("Party {id}: Iter {i} finished.");
        }

        let duration = start_time.elapsed();

        let avg_time = duration / ITER_COUNT;

        // println!("Party {id}: Round {i} Average Time: {avg_time:?}");
        result[i] = avg_time.as_micros() as f64 / 1000.0;
    }

    tcp_tree.close().await?;

    let file = File::create(&format!("p{party_count}_id{id}_tcp_{suffix}.csv"))?;

    let writer = BufWriter::new(file);

    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record([
        "Round",
        "DataSize_KB",
        "DataSize_Bytes",
        "Time_ms",
        "PartyID",
        "NumParties",
    ])?;
    for i in 0..2 {
        wtr.serialize((
            i,
            chunk_sizes[i] >> 10,
            chunk_sizes[i],
            result[i],
            id,
            party_count,
        ))?;
    }

    wtr.flush()?;

    Ok(())
}
