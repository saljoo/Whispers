package fi.utu.tech.telephonegame.network;

import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
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
	private Socket s;
	private ArrayList<ClientHandler> clientHandlers = new ArrayList<>();

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
		//Ajetaan omassa säikeessä
		new Thread(() -> {
			System.out.printf("I should start listening for peers at port %d%n", serverPort);
			//Luodaan ServerSocket olio
			try (ServerSocket server = new ServerSocket(serverPort)) {
				while(true){
					//Odotetaan yhteydenottoja
					s = server.accept();
					//Luodaan uusi ClientHandler olio, joka ajetaan omassa säikeessään
					ClientHandler ch = new ClientHandler(s, this);
					ch.start();
					clientHandlers.add(ch);
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}).start();
		
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
		ClientHandler ch = new ClientHandler(clientSocket, this);
		ch.start();
		clientHandlers.add(ch);
	}

	/**
	 * This method is used to send the message to all connected neighbours (directly connected nodes)
	 * 
	 * @param out The serializable object to be sent to all the connected nodes
	 * 
	 */
	private void send(Serializable out) {
		// Send the object to all neighbouring nodes
		for(ClientHandler i : clientHandlers){
			i.send(out);
		}
	}

	public void setInQueue(Object message){
		try {
			this.inQueue.put(message);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public void setOutQueue(Serializable message){
		try {
			outQueue.put(message);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	//Itse luotu metodi
	/*public static Serializable receive(){
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
	}*/

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
