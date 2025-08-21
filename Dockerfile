FROM rust:1.85

WORKDIR /app

COPY . .

RUN cargo build --release -p p2p --bin bootstrap

EXPOSE 4001

CMD ["./target/release/bootstrap"]