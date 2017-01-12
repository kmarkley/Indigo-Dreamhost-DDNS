# Dreamhost DDNS

###Adapted from [dreampy-dns](https://github.com/gsiametis/dreampy_dns)

---
Simple indigo plugin creates actions to update Dreamhost DNS servers via API.

[API Key](https://panel.dreamhost.com/?tree=home.api) required.


Not tested with ipv6.


Tip: Dreamhost will throw an error if the domain has **no records at all**.  Since updating a record consists of first deleting the current record, this can be a problem. Create a TXT record to prevent this.
