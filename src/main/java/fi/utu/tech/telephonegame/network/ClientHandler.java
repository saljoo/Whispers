package fi.utu.tech.telephonegame.network;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

//Class to handle receiving and sending of the messages by using threads
public class ClientHandler extends Thread{
    private Socket client;
    private NetworkService nS;
    private ObjectOutputStream oOs;
    private ObjectInputStream oIn;

    //Constructor of the class
    public ClientHandler(Socket s, NetworkService nS){
        this.client = s;
        this.nS = nS;
    }

    public void run(){
        try {
            //Create inputstream and outputstream using client socket
            InputStream iS = client.getInputStream();
            OutputStream oS = client.getOutputStream();
            oOs = new ObjectOutputStream(oS);
            oIn = new ObjectInputStream(iS);
        } catch (IOException e){
            e.printStackTrace();
        }
        while (true) {
            try{
                //Read incoming message
                Object message = oIn.readObject();
                //Add message to inQueue
                nS.getInputQueue().add(message);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    //Method to send messages
    public void send(Object message){
        try{
            oOs.writeObject(message);
            oOs.flush();
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}