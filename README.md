# LNDhub API

A plugin for [BTCPay Server](https://github.com/btcpayserver) to add a LNDhub-compatible API for stores.
This means that your store's Lightning wallet can be used with the following wallet apps:

- [BlueWallet](https://bluewallet.io/)
- [Zeus](https://zeusln.app/)
- [Alby](https://getalby.com/)

These wallets offer import features, so that you can easily import your store's Lightning wallets into these apps.

:::tip NOTE
The prerequisite for a Lightning wallet to be accessible like this is enabling the plugin for your store.
Please note that this offers full access to the Lightning node that is connected to the store, not just the BTCPay Server-related activity.
:::

## Importing the wallet

On the LNDhub API settings page you will find the "Connect LNDhub-compatible wallet" section.
It has a QR code and the Access URL, which contain the details (server URL and credentials) to connect the apps.

:::danger WARNING
The credentials allow unrestricted access to your store's Lightning node.
Treat the QR code and Access URL as confidential information!
:::

### BlueWallet

In BlueWallet you can use this path to import the wallet:

`Add Wallet > Import Wallet > Scan or import file`.

You can then scan the QR code from the LNDhub API plugin page.
Once the wallet is imported, you can also set a name.

### Zeus

In Zeus you can use this path to import the wallet:

- Open the settings by clicking on the node icon in the top left corner.
- In the settings click the node (first row) to get to the list of nodes.
- Click the plus icon in the top right corner to add a new node/wallet.

You will land on the following screen and have to …

- Choose "LNDHub" as the "Node Interface"
- Enable the "Existing account" toggle
- Click the "Scan LNDHub QR" button and scan the code

### Alby

In the Alby account dropdown, choose "Add a new account".
On the "Add a new lightning account" choose "LNDhub (BlueWallet)".

Now you can either copy and paste the account URL from the LNDhub API plugin page or scan the QR code.
Once the account is initialized, you should see a "Success!" message.

## Support this plugin

[![Support this plugin](./docs/img/support.png)](lightning:LNURL1DP68GURN8GHJ7AMPD3KX2AR0VEEKZAR0WD5XJTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHKXUN0WAJX2ER9V9E8G6PN8QSKVTEZ)
