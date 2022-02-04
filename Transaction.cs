using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using EllipticCurve;
namespace RootCoin
{
    class Transaction
    {
        public PublicKey FromAddress { get; set; }
        public PublicKey ToAddress { get; set; }
        public decimal Amount { get; set; }
        public Signature Signature { get; set; }


        public Transaction(PublicKey FromAddress, PublicKey ToAddress, decimal amount)
        {
            this.FromAddress = FromAddress;
            this.ToAddress = ToAddress;
            this.Amount = amount;

        }
        public void SignTransaction(PrivateKey signingKey)
        {
            string fromAddressDER = BitConverter.ToString(FromAddress.toDer()).Replace("-", "");
            string signingDER = BitConverter.ToString(signingKey.toDer()).Replace("-", "");

            //if (fromAddressDER != signingDER)
            //{
              //  throw new Exception("you cannot sign transactions for other wallet!");
            //}
            string txHash = this.CalculateHash();
            this.Signature = Ecdsa.sign(txHash, signingKey);
        }
        public string CalculateHash()
        {
            string fromAddressDER = BitConverter.ToString(FromAddress.toDer()).Replace("-", "");
            string toAddressDER = BitConverter.ToString(ToAddress.toDer()).Replace("-", "");
            string transactionData = fromAddressDER + toAddressDER + Amount;
            byte[] tdBytes = Encoding.ASCII.GetBytes(transactionData);
            return BitConverter.ToString( SHA256.Create().ComputeHash(tdBytes)).Replace("-", "");
        }
        public bool IsValid()
        {
            if (this.FromAddress is null) return true;

            if(this.Signature is null)
            {
                throw new Exception("No signature on this transaction");
            }
            return Ecdsa.verify(this.CalculateHash(), this.Signature, this.FromAddress);
        }

    }
}
