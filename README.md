# ct-submitter

Some Rust code for submitting a cert to all of Chrome's trusted CT logs and getting back the SCTs

Usage:

```
$ cargo run path/to/chain.pem
```

Where `chain.pem` is a file with the complete cert chain.

Example:

```
❯❯❯ cargo run example-chain.pem
    Finished dev [unoptimized + debuginfo] target(s) in 0.0 secs
     Running `target/debug/ct-submitter example-chain.pem`
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Log                    | SCT                                                                                                                                                              |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Google 'Icarus' log    | ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLcpMMM9OVFR/R4AAABW4lgjG4AAAQDAEcwRQIhAL6epRLVUnk7sIrtfc7jXsJFjwQpgz/qVwHsIbB8k3jNAiA/29s01vQBMEez5DhL8SfuIcWX2w1zrIUuUMCM3RjXdQ== |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Google 'Pilot' log     | AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABW5ONx1gAAAQDAEcwRQIhAMpOkC4QcLa98ks8o3WMSgUaN0h/LYo8Rvc6Z1b6ZiFsAiBf+0Iun0ZVQV6Zkur5aJfWW1/j2gGIwX51mdmrbN6nKw== |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Google 'Rocketeer' log | AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABW5YpEWMAAAQDAEgwRgIhAIHTcgnOY6wMIAvfCZgu9XdmmqdaVjqlJA80tMz6q8/IAiEAiM6BcygjOGAaaS/QeH/V34xnBeshUCu2j3F6HdtQ6tw= |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| WoSign log             | AEGy3C6J5jzkrxunuym/aMbe5vnxzAR+MN/647O6JZJjAAABW4lzUiEAAAQDAEYwRAIgat0S/80gyWkMPbWrmmPShx76SYjlCelNyMnZB08oqRUCIDyXxyBGGgdHAGdgwVnnK8ug16XhZGSukzDf5eRE9m2y     |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```
