var express = require('express');
var app = express();
var Wallet = require('ethereumjs-wallet');
var EthUtil = require('ethereumjs-util');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

class Transaction {
   
  constructor(fromAddress, toAddress, amount) {
    this.fromAddress = fromAddress;
    this.toAddress = toAddress;
    this.amount = amount;
    this.timestamp = Date.now();
  }

  calculateHash() {
    return crypto.createHash('sha256').update(this.fromAddress + this.toAddress + this.amount + this.timestamp).digest('hex');
  }
  signTransaction(signingKey) {
    // You can only send a transaction from the wallet that is linked to your
    // key. So here we check if the fromAddress matches your publicKey
    if (signingKey.getPublic('hex') !== this.fromAddress) {
      throw new Error('You cannot sign transactions for other wallets!');
    }
    

    // Calculate the hash of this transaction, sign it with the key
    // and store it inside the transaction obect
    const hashTx = this.calculateHash();
    const sig = signingKey.sign(hashTx, 'base64');

    this.signature = sig.toDER('hex');
  }
  isValid() {
    // If the transaction doesn't have a from address we assume it's a
    // mining reward and that it's valid. You could verify this in a
    // different way (special field for instance)
    if (this.fromAddress === null) return true;

    if (!this.signature || this.signature.length === 0) {
      throw new Error('No signature in this transaction');
    }

    const publicKey = ec.keyFromPublic(this.fromAddress, 'hex');
    return publicKey.verify(this.calculateHash(), this.signature);
  }
}

class Block {
   
  constructor(timestamp, transactions, previousHash = '') {
    this.previousHash = previousHash;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.nonce = 0;
    this.hash = this.calculateHash();
  }

 
  calculateHash() {
    return crypto.createHash('sha256').update(this.previousHash + this.timestamp + JSON.stringify(this.transactions) + this.nonce).digest('hex');
  }

  mineBlock(difficulty) {
    while (this.hash.substring(0, difficulty) !== Array(difficulty + 1).join('0')) {
      this.nonce++;
      this.hash = this.calculateHash();
    }

    console.log('Block mined:' +this.hash);
  }

  hasValidTransactions() {
    for (const tx of this.transactions) {
      if (!tx.isValid()) {
        return false;
      }
    }

    return true;
  }
}

class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.difficulty = 4;
    this.pendingTransactions = [];
    this.miningReward = 100;
  }

  createGenesisBlock() {
    return new Block(Date.parse('2020-28-05'), [], '0');
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  minePendingTransactions(miningRewardAddress) {
    const rewardTx = new Transaction(null, miningRewardAddress, this.miningReward);
    this.pendingTransactions.push(rewardTx);

    const block = new Block(Date.now(), this.pendingTransactions, this.getLatestBlock().hash);
    block.mineBlock(this.difficulty);

    console.log('Block successfully mined!');
    this.chain.push(block);

    this.pendingTransactions = [];
  }

  
  addTransaction(transaction) {
    if (!transaction.fromAddress || !transaction.toAddress) {
      throw new Error('Transaction must include from and to address');
    }

    // Verify the transactiion
    if (!transaction.isValid()) {
      throw new Error('Cannot add invalid transaction to chain');
    }
    
    if (transaction.amount <= 0) {
      throw new Error('Transaction amount should be higher than 0');
    }
    
 

    this.pendingTransactions.push(transaction);
    console.log('transaction added: %s', transaction);
  }


  getBalanceOfAddress(publickey) {
    let balance = 0
    ;

    for (const block of this.chain) {
      for (const trans of block.transactions) {
        if (trans.fromAddress === publickey) {
          balance -= trans.amount;
        }

        if (trans.toAddress === publickey) {
          balance += trans.amount;
        }
      }
    }

    console.log('getBalanceOfAdrees: %s', balance);
    return balance;
  }

  
  getAllTransactionsForWallet(address) {
    const txs = [];

    for (const block of this.chain) {
      for (const tx of block.transactions) {
        if (tx.fromAddress === address || tx.toAddress === address) {
          txs.push(tx);
        }
      }
    }

    console.log('get transactions for wallet count: %s', txs.length);
    return txs;
  }

  isChainValid() {
    // Check if the Genesis block hasn't been tampered with by comparing
    // the output of createGenesisBlock with the first block on our chain
    const realGenesis = JSON.stringify(this.createGenesisBlock());

    if (realGenesis !== JSON.stringify(this.chain[0])) {
      return false;
    }

    // Check the remaining blocks on the chain to see if there hashes and
    // signatures are correct
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];

      if (!currentBlock.hasValidTransactions()) {
        return false;
      }

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false;
      }
    }
    console.log('valid!');
    return true;
  }
}
// var accountPassword="abcd";
// var key=Wallet.generate(accountPassword);
// var privateKey=key._privKey;
// var wallet=Wallet.fromPrivateKey(privateKey);
// privateKey=privateKey.toString('hex');
// var keyStoreData=wallet.toV3(accountPassword);
// const keystoreFilename = wallet.getV3Filename();
// const publicKey = wallet.getPublicKeyString();

//const address = wallet.getAddressString();
//  const myKey=ec.keyFromPrivate('bffe98de4ffdc49d83c57925528f95996e5836ad8677bad237c72db5a8284e40');
//  const public=myKey.getPublic('hex');
 


//  let bin =new Blockchain();
//  const trans1=new Transaction(public,'b',10);
//  trans1.signTransaction(myKey);
//  bin.addTransaction(trans1);
//  const trans2=new Transaction(public,'c',20);
//  trans2.signTransaction(myKey);
//  bin.addTransaction(trans2);
// //  const trans2=new Transaction(public,'c',400);
// //  trans2.signTransaction(myKey);
// //  bin.addTransaction(trans2);
//  bin.minePendingTransactions('c');
 
 
//  console.log('tiền của a sau ck :',bin.getBalanceOfAddress(public));
//  console.log('tiền của b sau ck :',bin.getBalanceOfAddress('b'));
//  console.log('tiền của c sau ck :',bin.getBalanceOfAddress('c'));
//  var transHistory=bin.getAllTransactionsForWallet(public);
//  for(let i of transHistory) console.log(i,'\n');
//--------------------------------------------------------------------------------------------------

// var privateKey='061ce8b95ca5fd6f55cd97ac60817777bdf64f1670e903758ce53efc32c3dffeb';

// const privateKeyBuffer = EthUtil.toBuffer(privateKey);
// const wallet = Wallet.fromPrivateKey(privateKeyBuffer);
// var accountPassword="abcd";
// var key=Wallet.generate(accountPassword);
// var privateKey=key._privKey;
// var wallet=Wallet.fromPrivateKey(privateKey);
// privateKey=privateKey.toString('hex');
// var keyStoreData=wallet.toV3(accountPassword);
// const keystoreFilename = wallet.getV3Filename();
// const publicKey = wallet.getPublicKeyString();

// const address = wallet.getAddressString();

//console.log(privateKey);
//console.log(address);
 

app.get('/', function (req, res) {
  res.send('Hello World!');
});
app.get('/createWallet/password',function(req,res){
 
  const accountPassword = req.query.x;
  var key=Wallet.generate(accountPassword);
  var privateKey=key._privKey;
  var wallet=Wallet.fromPrivateKey(privateKey);
  privateKey=privateKey.toString('hex');


  res.json(privateKey);

})

app.get('/transaction',function(req,res){
  const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
  const privateKey= req.query.pri;
  const userAddress=req.query.useradd;
  const amount=+req.query.amount;
  const myKey=ec.keyFromPrivate(privateKey);
 const public=myKey.getPublic('hex');
 let bin =new Blockchain();
 const trans1=new Transaction(public,userAddress,amount);
 trans1.signTransaction(myKey);
 bin.addTransaction(trans1);
 bin.minePendingTransactions('system');
 const a=bin.getAllTransactionsForWallet(public);
 res.json(a);
})

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});