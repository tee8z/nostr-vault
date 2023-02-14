# nostr-vault
Simple server to store private keys and to be used for logins from nostr clients


A UI issue faced by nostr clients is requiring users to paste in their private key to pull up all their data on initial onboarding. This is fine if a user only uses one nostr client, but as that number grows, and the user still wants to have the same audience across clients, this becomes a security concern.
The more often a private key is moved around, the more likely it will become compromised. One possible solution to this problem is having a number of vault services running that any nostr client can connect with. The user would select which vault service they store their private key with, then the client can just pull down the encrypted private key and de-encrypt client side based on a password only the user knows. A user would also want to keep a copy of their private key stored locally offline. This can be used to recover their audience incase of a lost password or one of these vault services being forced to spin down. There is no way one of these services would be able to reset the password to encrypt the private key, since it happens client side. It is on the user to know the password or have a backup of their private key.


With all that in mind, this API has just three endpoints:
* /health_check -- used to see if the service is running 
* /upload_key -- uploads sha256 encrypted private key to the service
* /fetch_key -- retrieves a private key based on a provided PIN & nip05ID

More documentation and a demo example of this API can be seen here: https://nostr-vault.duckdns.org/swagger-ui

Example calling this API:
```
curl -v -X 'GET' 'https://nostr-vault.duckdns.org/health_check' -H 'accept: */*'
```

Additionally, please feel free to spin up your own nostr-vault. [How To Run](CONTRIBUTING.md)

This is just step one of making the onboarding easier, next we will need to build a simple button that can be imported into many clients that can communicate with these nostr-vaults, a problem for another day.
