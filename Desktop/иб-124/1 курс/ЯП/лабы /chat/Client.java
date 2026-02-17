import java.io.*;
import java.net.*; 
import java.util.Scanner; 

public class Client {  
    private static final String SERVER_IP = "localhost"; // Адрес сервера 
    private static final int SERVER_PORT = 1234; // Порт на котором работает сервер
    public static void main(String[] args) { 
        try (
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);  // Создаем соединение с сервером по указанному IP и порту
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));  // Для чтения данных от сервера
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);  // Для отправки данных на сервер
            Scanner scanner = new Scanner(System.in)  // Для чтения ввода пользователя
        ) {
            // Создаем новый поток для чтения сообщений от сервера
            new Thread(() -> {
                try {
                    String serverMessage;
                    // Читаем сообщения от сервера, пока они не закончились
                    while ((serverMessage = in.readLine()) != null) {
                        System.out.println(serverMessage);  // Выводим сообщения на экран
                    }
                } catch (IOException e) {
                    System.out.println("Отключено от сервера.");  // Если ошибка чтения, сообщаем, что соединение разорвано
                }
            }).start(); // Запускаем поток

            // Основной цикл клиента: ждем ввода от пользователя
            while (scanner.hasNextLine()) {
                String userInput = scanner.nextLine();  // Читаем строку ввода
                out.println(userInput);  // Отправляем введенную строку на сервер
                if (userInput.equalsIgnoreCase("/exit")) break;  // Если пользователь вводит команду "/exit", выходим из цикла
            }

        } catch (IOException e) {
            e.printStackTrace();  // Если происходит ошибка при подключении или в процессе работы, выводим информацию об ошибке
        }
    }
}

//javac Client.java
//java Client
