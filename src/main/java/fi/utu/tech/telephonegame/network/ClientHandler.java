package fi.utu.tech.telephonegame.network;

//import fi.utu.tech.telephonegame.Message;
//import fi.utu.tech.telephonegame.MessageBroker;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class ClientHandler extends Thread{
    private Socket client;
    private NetworkService nS;
    private ObjectOutputStream oOs;

    //Konstruktori
    public ClientHandler(Socket s, NetworkService nS){
        this.client = s;
        this.nS = nS;
    }

    public void run(){
        try {
            OutputStream oS = client.getOutputStream();
            oOs = new ObjectOutputStream(oS);
            InputStream iS = client.getInputStream();
            ObjectInputStream oIn = new ObjectInputStream(iS);
            while (true) {
                Object message = oIn.readObject();
                System.out.println(message);
                nS.setInQueue(message);
            }
        } catch (Exception e) {
            throw new Error(e.toString());
        }
    }

    public void send(Serializable message){
        try{
            oOs.writeObject(message);
            oOs.flush();
        } catch (IOException e){
            e.printStackTrace();
        }
        
    }
}