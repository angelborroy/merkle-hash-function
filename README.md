# merkle-hash-function

Sample algorithm implementing Merkle–Damgård hash function for teaching purposes.

## Requirements

* Java 11
* Maven 3.5

## Building

```
$ mvn clean package
```

## Running

Binary hashing

```
$ java -cp target/classes es.usj.crypto.HashApp

Message: 01111010011111110100101111111011
Digest:  11001110
```

File hashing

```
$ java -cp target/classes es.usj.crypto.HashFileApp

deb4d93ca94f7ec3d2d5e86f46f17d4be889023f
```
