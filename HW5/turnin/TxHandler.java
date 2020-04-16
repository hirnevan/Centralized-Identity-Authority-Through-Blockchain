//Evan Hirn
//u1062335

import java.util.ArrayList;
import java.util.List;

public class TxHandler {

	/* Creates a public ledger whose current UTXOPool (collection of unspent 
	 * transaction outputs) is utxoPool. This should make a defensive copy of 
	 * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
	 */
	UTXOPool current_utxoPool;
	public TxHandler(UTXOPool utxoPool) {
		if(utxoPool == null)
		{
			current_utxoPool = new UTXOPool();
		}
		else
		{
			current_utxoPool = new UTXOPool(utxoPool);
		}
	}

	/* Returns true if 
	 * (1) all outputs claimed by tx are in the current UTXO pool, 
	 * (2) the signatures on each input of tx are valid, 
	 * (3) no UTXO is claimed multiple times by tx, 
	 * (4) all of tx’s output values are non-negative, and
	 * (5) the sum of tx’s input values is greater than or equal to the sum of   
	        its output values;
	   and false otherwise.
	 */

	public boolean isValidTx(Transaction tx) {
		// IMPLEMENT THIS
		ArrayList<UTXO> usedHashes = new ArrayList<UTXO>();
		ArrayList<Transaction.Input> inputs = tx.getInputs();
		ArrayList<Transaction.Output> outputs = tx.getOutputs();

		double input_sum = 0;
		for(int i = 0; i < inputs.size(); i++)
		{
			Transaction.Input input = inputs.get(i);
			UTXO in_utxo = new UTXO(input.prevTxHash, input.outputIndex);
			Transaction.Output output = current_utxoPool.getTxOutput(in_utxo);
			RSAKey key;
			try{
			key = output.address;
			}
			catch(Exception e){
				return false;
			}
			if (!current_utxoPool.contains(in_utxo) || usedHashes.contains(in_utxo) || !key.verifySignature(tx.getRawDataToSign(i), input.signature))
			{
				return false;
			}
			input_sum += output.value;
			usedHashes.add(in_utxo);
		}

		double output_sum = 0;
		for(int i = 0; i < outputs.size(); i++)
		{
			if(outputs.get(i).value < 0)
				return false;
			output_sum += outputs.get(i).value;
		}
		if(input_sum < output_sum)
			return false;
		
		return true;
	}

	/* Handles each epoch by receiving an unordered array of proposed 
	 * transactions, checking each transaction for correctness, 
	 * returning a mutually valid array of accepted transactions, 
	 * and updating the current UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		// IMPLEMENT THIS
		ArrayList<Transaction> trans_list = new ArrayList<Transaction>();
		for(int i = 0; i < possibleTxs.length; i++){
			if(isValidTx(possibleTxs[i]))
			{
				trans_list.add(possibleTxs[i]);
				ArrayList<Transaction.Input> inputs = possibleTxs[i].getInputs();
				for(int a = 0; a < inputs.size(); a++)
				{
					UTXO utxo = new UTXO(inputs.get(a).prevTxHash, inputs.get(a).outputIndex);
					current_utxoPool.removeUTXO(utxo);
				}

				ArrayList<Transaction.Output> outputs = possibleTxs[i].getOutputs();
				for (int x = 0; x < outputs.size(); x++) {
					Transaction.Output output = outputs.get(x);
					
                    UTXO utxo = new UTXO(possibleTxs[i].getHash(), x);
                    current_utxoPool.addUTXO(utxo, output);
                }
			}
		}

		Transaction[] array = trans_list.toArray(new Transaction[0]);
		return array;
	}

} 
