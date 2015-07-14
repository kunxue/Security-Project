
import java.io.*;
import java.net.*;
import java.awt.*;
import java.awt.event.*;
import java.security.*;

import javax.crypto.spec.*;
import javax.crypto.*;
import javax.swing.*;

public class Client extends JFrame{
	//GUI
	private JTextField usernamefield;
	private JPasswordField passwordfield;
	private JTextArea textArea;
	private JTextField messagefield;
	private JPanel panel1,panel2;
	private JButton connectButton ;
	private JButton sendButton;

	//
	String IDc,ADc,password;
	String IDtgs,IDs;
	long TS1,TS2,TS3,TS4,TS5;
	long Lifetime1,Lifetime2;
	Ticket_tgs Tickettgs;
	Ticket_s Tickets;
	Authenticator_tgs at;
	Authenticator_s as;
	byte[] subkey1;
	boolean pass;
	private Utils utils =new Utils();
	//socket变量
	Socket clientASSocket,clientTGSSocket,clientServerSocket;
	int port;
	ObjectOutputStream outstream,outstream2,outstream3;
	ObjectInputStream instream,instream2,instream3;
	
	//Key变量
	PrivateKey clientprikey;

	//加密解密辅助类实例
	RSACryptography en;
	
	public Client() throws Exception{
		//GUI
		super("SSKBS客户端");
		
		Container container = getContentPane();
		container.setLayout( new BorderLayout());
		
		panel1 = new JPanel();
		panel1.setLayout( new FlowLayout());
		container.add(panel1,BorderLayout.NORTH);
		
		JLabel usernameLabel = new JLabel("帐号:");
		panel1.add(usernameLabel);
		usernamefield = new JTextField(10);
		panel1.add(usernamefield);
		
		JLabel passwordLabel = new JLabel("密码:");
		panel1.add(passwordLabel);
		passwordfield = new JPasswordField(10);
		panel1.add(passwordfield);		
		
		connectButton = new JButton("连接");
		panel1.add(connectButton);
		connectButton.addActionListener(
				new ActionListener(){
					public void actionPerformed (ActionEvent event)
					{
						try{	
							IDc = usernamefield.getText();
							authentication();
						}
						catch(Exception ex)
						{
							ex.printStackTrace();
						}
					}
				}
		);
		
		textArea = new JTextArea(10,20);
		textArea.setEditable(false);
		container.add( new JScrollPane(textArea),BorderLayout.CENTER);
		
		panel2 = new JPanel();
		panel2.setLayout( new FlowLayout());
		container.add(panel2,BorderLayout.SOUTH);
		
		messagefield = new JTextField(20);
		panel2.add(messagefield);
		
		sendButton = new JButton("发送");
		sendButton.addActionListener(
				new ActionListener(){
					public void actionPerformed (ActionEvent event)
					{
						try{	
							if(pass){
								talkToServer("[From IP:"+ADc+"]->" +messagefield.getText());
							}
							else{
								JOptionPane.showMessageDialog(null,"还未登录验证，请先登录验证后再发送消息！","", JOptionPane.ERROR_MESSAGE);
							}
						}
						catch(Exception ex)
						{
							ex.printStackTrace();
						}
					}
				}
		);
		panel2.add(sendButton);
		
		
		setSize(400, 300);
		setVisible(true);
		
		
		en = new RSACryptography();
		ADc = "localhost";
		
	}
	
	/**
	 * 初始化client端的socket方法
	 * port:所要连接的服务器的端口:5000--AS
	 */
	public void initClientASSocket(int port)
	{	
		this.port = port;
		try {
			clientASSocket = new Socket("localhost", port);
			outstream = new ObjectOutputStream(clientASSocket.getOutputStream());
			instream = new ObjectInputStream(clientASSocket.getInputStream());
			outstream.flush();
			textArea.append("与AS通信的socket初始化完毕...\n");
			System.out.println("与AS通信的socket初始化完毕");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	/**
	 * 初始化client端的socket方法
	 * port:所要连接的服务器的端口:6000--TGS
	 */
	public void initClientTGSSocket(int port){
		this.port = port;
		try {
			System.out.println(ADc+"*****"+port);
			clientTGSSocket = new Socket("localhost", port);
			outstream2 = new ObjectOutputStream(clientTGSSocket.getOutputStream());
			instream2 = new ObjectInputStream(clientTGSSocket.getInputStream());
			outstream2.flush();
			System.out.println("tgs socket init ok");
			textArea.append("与TGS通信的socket初始化完毕...\n");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	/**
	 * 初始化client端的socket方法
	 * port:所要连接的服务器的端口:7000--Server
	 */
	public void initClientServerSocket(int port){
		this.port = port;
		try {
			clientServerSocket = new Socket(InetAddress.getLocalHost(), port);
			outstream3 = new ObjectOutputStream(clientServerSocket.getOutputStream());
			instream3 = new ObjectInputStream(clientServerSocket.getInputStream());
			outstream3.flush();
			System.out.println("service socket init ok");
			textArea.append("与Service Server通信的socket初始化完毕...\n");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	
	/**
	 * 对明文进行加密，这里都是用client的私钥加密,所以采用RSA非对称加密算法
	 * @param t	明文
	 * @param k client的私钥
	 * @return 密文
	 * @throws Exception
	 */
	public byte[] decrypt(byte[] t,Key k)throws Exception
	{
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE,k);
		byte[] newPlainText = cipher.doFinal(t);
		System.out.println("用client的私钥解密完毕,client_privatekey:  "+new String(newPlainText,"UTF8"));
		textArea.append("用client的私钥解密完毕,client_privatekey:"+new String(newPlainText)+"...\n");
		return newPlainText;
	}
	public void getKeyFromFile()
	{
		try
		{
			String file = "keys/prclient.txt";
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
			clientprikey = (PrivateKey)in.readObject();
			System.out.println(clientprikey);
			//textArea.append("用password解密完毕，已获得当前client的私钥"+clientprikey+"...\n");
			in.close();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
	}
	
	/**
	 * 生成一个时间戳。
	 * @return
	 */
	public long getTimeStamp()
	{	
		long now = System.currentTimeMillis();
		return now;
	}
	
	
	/**
	 * 判断当前会话是否在有效期内
	 * @param ts1
	 * @param ts2
	 * @param lifetime 有效期的长度
	 * @return true 有效 ；false 无效
	 */
	public boolean isInSession(long ts1,long ts2,long lifetime)
	{	
		if(ts1 + lifetime > ts2)
			return true;
		else return false;
	}
	
	/**
	 * 验证步骤
	 * 验证第一步，
	 * 向 Authenticator Server 认证
	 * 如果用户名未samantha则继续认证
	 * 如果不是则退出认证
	 */
	
	public boolean Step1(){
		textArea.append("开始向Authenticator Server发送认证请求...\n");
		try
		{
			/**
			 * (1)C->AS: IDc || ADc || TS1
			 */
			TS1 = getTimeStamp();
			C_AS c_as = new C_AS(IDc,TS1); 
			//Client->AS
			sendmessage(c_as,outstream);
			
			/**AS->Client
			 * (2)AS->C: 
			 * Tickettgs = Epub-tgs[Kpub-c || IDc || ADc || IDtgs || TS2 || Lifetime1] 
			 * Epub-c[IDtgs || TS2 || Lifttime1 || Tickettgs]
			 */
			while(true)
			{
				Object object = receivemessage(instream);
				//用户名不合法
				if(object!=null&&object instanceof String)
				{
					String result = (String)object;
					if(result.equals("false"))
					{	
						System.out.println("用户名验证结果：错误的用户名,请重新启动客户端\nAS上未通过验证");
						textArea.append("用户名验证结果：错误的用户名,请重新启动客户端\nAS上未通过验证\n");
						return false;
					}
					else{
						System.out.println("AS验证出错,请重新启动客户端\nAS上未通过验证");
						textArea.append("AS验证出错,请重新启动客户端\nAS上未通过验证\n");
						return false;
					}
					
				}
				//用户名合法
				if(object!=null&&object instanceof AS_C)
				{
					System.out.println("用户名验证结果：正确");
					textArea.append("用户名验证结果：正确,North为唯一有效用户名\n");
					textArea.append("用户名验证完毕\n");
					System.out.println("用户名验证完毕");
					textArea.append("Msg:[  form Client to AS\n");
					textArea.append("TS1:"+TS1+"\n");
					textArea.append("IDc:"+IDc+"\n");
					textArea.append("ADc:"+ADc+"\n");
					textArea.append("]\n");
					AS_C as_c = (AS_C)object;;
					IDtgs = new String(decrypt(as_c.IDtgs,clientprikey));
					Tickettgs = as_c.Tickettgs;
					TS2 = as_c.TS2;
					Lifetime1 = as_c.Lifetime1;
					textArea.append("Msg:[ from AS to Client \n");
					textArea.append("IDtgs:"+IDtgs+"\n");
					textArea.append("Ticket_tgs:"+Tickettgs+"\n");
					textArea.append("TS2:"+TS2+"\n");
					textArea.append("Lifetime1:"+Lifetime1+"]\n");
					//验证时间的合法性
					if(!isInSession(TS1,TS2,Lifetime1)){
						textArea.append("client端的时间合法性未通过验证\n");	
						return false;
					}
					textArea.append("client端的时间合法性验证通过\n");
					System.out.println("时间验证通过");
					break;
				}
			}
			System.out.println("AS服务器上验证完毕");
			textArea.append("Client向AS验证完毕\n");
			return true;
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		textArea.append("Client向AS验证完毕false\n");
		return false;
	}
	/**
	 * 验证步骤
	 * 验证第二步，
	 * 向 Ticket Granting Server 认证，
	 */
	public boolean Step2(){
		textArea.append("开始向TGS发送请求\n");
		try
		{
			/**
			 * (3)C->TGS: IDs || Tickettgs || Authenticatortgs
			 * Tickettgs = Epub-tgs[Kpub-c || IDc || ADc || IDtgs || TS2 || Lifetime1] 
			 * Authenticatortgs = Epri-c[IDc || ADc || TS3]
			 */
			IDs = "A";
			
			byte[] IDc_m =en.encrypt_decrypt(IDc.getBytes(), clientprikey, true);
			byte[] ADc_m = en.encrypt_decrypt(ADc.getBytes(),clientprikey, true);
			TS3 = getTimeStamp();
			//封装Authenticator_tgs
			at= new Authenticator_tgs(IDc_m,ADc_m,TS3);
			//封装C -> TGS
			C_TGS c_tgs = new C_TGS(IDs.getBytes(),Tickettgs,at);
			System.out.println("start to send C2TGS ");
			textArea.append("发往TGS的消息封装完成\n");
			sendmessage(c_tgs,this.outstream2);
			textArea.append("Msg:[  form Client to TGS\n");
			textArea.append("IDc:"+IDc+"\n");
			textArea.append("IDs:"+IDs+"\n");
			textArea.append("ADc:"+ADc+"\n");
			textArea.append("TS3:"+TS3+"\n");
			textArea.append("Ticket_tgs:"+Tickettgs+"\n");
			textArea.append("]\n");
			
			
			/**
			 * (4)TGS->C: Epub-c[IDs || TS4 || Tickets] 
			 * Tickets = Epub-s[Kpub-c || IDc || ADc || IDs || TS4 || Lifetime2]
			 */
			while(true)
			{	
				Object o2 = receivemessage(instream2);
				if(o2!=null&&o2 instanceof String)
				{
					String result = (String)o2;
					if(result.equals("false"))
					{	System.out.println("TGS上验证未通过");
						textArea.append("TGS上验证未通过\n");
						return false;
					}
					
				}
				if(o2!=null&&o2 instanceof TGS_C)
				{
					TGS_C tgs_c = (TGS_C)o2;
					String IDs_from_tgs = new String(decrypt(tgs_c.IDs,clientprikey));
					TS4 = tgs_c.TS4;
					Tickets = tgs_c.ts;
					Lifetime2 = tgs_c.Lifetime2;
					textArea.append("Msg:[ from TGS to Client \n");
					//textArea.append("IDs:"+IDs_from_tgs+"\n");
					textArea.append("Ticket_s:"+this.Tickettgs+"\n");
					textArea.append("TS4:"+this.TS4+"\n");
					textArea.append("Lifetime2:"+this.Lifetime2+"]\n");
					//时间合法性验证
					if(!isInSession(TS3,TS4,Lifetime2))
					{	
						System.out.println("TGS上时间验证未通过");
						textArea.append("TGS上时间验证未通过\n");
						return false;
					}
					//验证server ID是否为请求的server ID,即"SaleServer"
					if(!IDs_from_tgs.equals(this.IDs))
					{	System.out.println("TGS上ID service验证未通过");
						textArea.append("TGS上对ID service的验证未通过\n");
						return false;
					}
					break;
				}
			}
			textArea.append("TGS上的验证完毕:通过\n");
			System.out.println("TGS服务器上验证完毕");
			return true;
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		return false;
	}
	public boolean Step3(){
		textArea.append("开始向Service Server发送请求\n");
		try
		{
			/**
			 * (5)C->S: Tickets || Authenticators
			 * Tickets = Epub-s[Kpub-c || IDc || ADc || IDs || TS4 || Lifetime2] 
			 * Authenticators = Epri-c[IDc || ADc || TS5 ] 
			 */
			TS5 = this.getTimeStamp();
			byte[] IDc_m = en.encrypt_decrypt(IDc.getBytes(), clientprikey, true);
			byte[] ADc_m = en.encrypt_decrypt(ADc.getBytes(),clientprikey, true);
			
			this.as = new Authenticator_s(IDc_m,ADc_m,TS5);
			C_S c_s = new C_S(Tickets,as);
			
			textArea.append("Msg:[ from Client to Service Server \n");
			textArea.append("IDc:"+IDc+"\n");
			textArea.append("ADc:"+ADc+"\n");
			textArea.append("TS5:"+TS5+"\n");
			textArea.append("Ticket_s:"+Tickets+"\n");
			textArea.append("]\n");
			
			sendmessage(c_s,outstream3);
			System.out.println("send service msg(C_S) ok");
			/**
			 * (6)S->C: Epub-c [TS5 + 1 || Subkey2] 
			 * SessionKey = Subkey2 
			 */
			while(true)
			{
				Object o3 = receivemessage(instream3);
				if(o3!=null&&o3 instanceof String)
				{	
					String result = (String)o3;
					if(result.equals("false"))
					{	
						System.out.println("SServer上验证未通过");
						textArea.append("SServer上验证未通过\n");
						return false;
					}
					
				}
				if(o3!=null && o3 instanceof S_C)
				{	
					S_C s_c = (S_C)o3;
					long new_TS = s_c.TS5;
					textArea.append("Msg:[ from Service Server to Client \n");
					textArea.append("TS5:"+new_TS+"\n");
					textArea.append("Session Key:"+new String(s_c.subkey2,"utf-8")+"\n");
					textArea.append("]\n");
					
					if(!isInSession(this.TS5,new_TS,this.Lifetime2))
					{
						System.out.println("Client上时间验证未通过");
						textArea.append("Client上对Server传来的时间戳的验证未通过\n");
						return false;
						
					}
					subkey1 = s_c.subkey2;
					textArea.append("Client上对Server传来的时间戳的验证通过\n");
					System.out.println("Client上时间验证通过");
					break;
				}
				
			}
			textArea.append("AServer服务器上验证完毕,获得的sessionkey为'"+subkey1+"',可以开始通信\n");
			System.out.println("AServer服务器上验证完毕,获得的sessionkey为'"+subkey1+"',可以开始通信");
			return true;
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		return false;
		
	}
	/**
	 * 认证的整个流程
	 * 分为3个部分，
	 * 向 Authenticator Server 认证，包括用户名认证，
	 * 向 Ticket Granting Server 认证，
	 * 向 提供服务的 Server 认证
	 * @return
	 */
	public boolean authentication()throws Exception
	{	
		initClientASSocket(5000);
		password=new String(passwordfield.getPassword());
		if(password.equals("1234"))
		{	textArea.append("密码验证结果：正确\n");
		
			getKeyFromFile();
			if(Step1()){
				clientASSocket.close();
				initClientTGSSocket(6000);
				if(Step2()){
					clientTGSSocket.close();
					initClientServerSocket(9000);
					if(this.Step3()){
						pass = true;
						return true;
					}
				}
			}
		}
		else
		{
			textArea.append("密码验证结果：错误的密码,请重新启动客户端\nAS上未通过验证\n");
			return false;	
		}

		return false;
	}
	//发送消息方法
	public void sendmessage(Object object,ObjectOutputStream outstream)
	{
		try
		{
			outstream.writeObject(object);
			System.out.println("send a message ok");
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
	}
	//接收信息方法
	public Object receivemessage(ObjectInputStream instream)
	{
		try
		{
			return instream.readObject();
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		return null;
	}
	
	//通讯
	public void talkToServer(String str)
	{	
		try
		{	
			SecretKeySpec sessionKey = new SecretKeySpec(this.subkey1,"AES");
			AESKey a=new AESKey();
			byte[] cipher = a.AESencrypt(str.getBytes("utf-8"),sessionKey);
			System.out.println(new String(cipher,"utf-8"));
			System.out.println("..."+cipher.length);
			sendmessage(cipher,outstream3);
			System.out.println("send a msg Service Server ");
			textArea.append("send a msg Service Server\n");
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
	}
	
	public static void main(String args[]) throws Exception{
		Client applocation = new Client();
		applocation.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	
}
