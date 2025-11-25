use clap::Parser;
use network2::{Id, Participant, QuicTree};
use rand::RngCore;

const BASE_PORT: u16 = 8080;

const CHUNK_SIZE: usize = 600 * 1024;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    id: Id,
    #[arg(short, long)]
    party_count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let id = args.id;
    let party_count = args.party_count;

    let mut data = vec![0u8; CHUNK_SIZE * party_count];

    data.chunks_exact_mut(CHUNK_SIZE)
        .skip(id as usize)
        .take(1)
        .for_each(|part| {
            let mut rng = rand::rng();
            rng.fill_bytes(part);
        });

    let parties = Participant::from_default(party_count, BASE_PORT);

    // println!("Party {id}: {parties:?}");

    let quic_tree = QuicTree::new(id, parties).await?;

    quic_tree.share(&mut data, CHUNK_SIZE).await?;

    let start_time = std::time::Instant::now();

    for _i in 0..10 {
        quic_tree.share(&mut data, CHUNK_SIZE).await?;
        // println!("Party {id}: Iter {i} finished.");
    }

    let duration = start_time.elapsed();

    let avg_time = duration / 10;

    println!("Party {id}: Average Time: {avg_time:?}");

    Ok(())
}
