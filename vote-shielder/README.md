# Vote-Shielder

For the simplest example use commands:
```bash
./deploy/deploy.sh
```
```bash
cd cli
./target/release/shielder-cli deposit 0 10
```
```bash
./target/release/shielder-cli vote 0 6 4
```
```bash
./target/release/shielder-cli deposit 0 10
```
```bash
./target/release/shielder-cli vote 0 9 1
```
```bash
./target/release/shielder-cli decrypt
```

And you should be able to see amount final result equal to `[15, 5]`