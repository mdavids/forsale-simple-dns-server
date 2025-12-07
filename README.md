# forsale-simple-dns-server
A simple DNSSEC signing authoritative name server for testing purposes of the ForSale method.

## Caveats
- Probably full of bugs
- We also like to make it compliant with https://ednscomp.isc.org/ednscomp
  
## Vision
This server is a proof of concept of an authoritative name server that can act as a backend for the ForSale method defined in [draft-davids-forsalereg](https://datatracker.ietf.org/doc/html/draft-davids-forsalereg). We're starting simple, with some randomised variables for the asking price. But if time permits, we'd like to explore giving the server a backend database with a web frontend, allowing parties to list their domains for sale there and adjust things like the asking price with just a few clicks.

We're also considering business rules that, for example, adjust the currency of the asking price based on EDNS Client Subnet (ECS), and similar mechanisms. In short, a dynamic DNS server for ForSale purposes!

But all of this only if it cannot be also achieved by other, better, existing means (PowerDNS comes to mind).
