package fi.utu.tech.telephonegame.network;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TransferQueue;

public class NetworkService extends Thread implements Network {
	/*
	 * Do not change the existing class variables
	 * New variables can be added
	 */
	private TransferQueue<Object> inQueue = new LinkedTransferQueue<Object>(); // For messages incoming from network
	private TransferQueue<Serializable> outQueue = new LinkedTransferQueue<Serializable>(); // For messages outgoing to network
	private ServerSocket server = null;


	/*
	 * No need to change the construtor
	 */
	public NetworkService() {
		this.start();
	}



	/**
	 * Creates a server instance and starts listening for new peers on specified port
	 * The port used to listen incoming connections is provided by the template
	 * 
	 * @param serverPort Which port should we start to listen to?
	 * 
	 */
	public void startListening(int serverPort){
		System.out.printf("I should start listening for peers at port %d%n", serverPort);
		try {
			server = new ServerSocket(serverPort);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * This method will be called when connecting to a peer (other broken telephone
	 * instance)
	 * The IP address and port will be provided by the template (by the resolver)
	 * 
	 * @param peerIP   The IP address to connect to
	 * @param peerPort The TCP port to connect to
	 */
	public void connect(String peerIP, int peerPort) throws IOException, UnknownHostException {
		System.out.printf("I should connect myself to %s, port %d%n", peerIP, peerPort);
		Socket clientSocket = new Socket(peerIP, peerPort);
	}

	/**
	 * This method is used to send the message to all connected neighbours (directly connected nodes)
	 * 
	 * @param out The serializable object to be sent to all the connected nodes
	 * 
	 */
	private void send(Serializable out) {
		// Send the object to all neighbouring nodes
		try {
			FileOutputStream fout = new FileOutputStream("file.txt");
			ObjectOutputStream output = new ObjectOutputStream(fout);
			output.writeObject(out);
			output.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Serializable receive(){
		Serializable viesti = null;
		try {
			FileInputStream fis = new FileInputStream("file.txt");
			ObjectInputStream input = new ObjectInputStream(fis);
			viesti = (Serializable) input.readObject();
			input.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return viesti;
	}

	/*
	 * Don't edit any methods below this comment
	 * Contains methods to move data between Network and 
	 * MessageBroker
	 * You might want to read still...
	 */

	/**
	 * Add an object to the queue for sending
	 * 
	 * @param outMessage The Serializable object to be sent
	 */
	public void postMessage(Serializable outMessage) {
		try {
			outQueue.offer(outMessage, 1, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Get reference to the queue containing incoming messages from the network
	 * 
	 * @return Reference to the queue incoming messages queue
	 */
	public TransferQueue<Object> getInputQueue() {
		return this.inQueue;
	}

	/**
	 * Waits for messages from the core application and forwards them to the network
	 */
	public void run() {
		while (true) {
			try {
				send(outQueue.take());
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

}
