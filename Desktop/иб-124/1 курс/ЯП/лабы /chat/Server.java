import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class Server {
    private static final int PORT = 1234;
    private static final Map<String, ClientHandler> onlineUsers = new ConcurrentHashMap<>();
    private static final ExecutorService threadPool = Executors.newCachedThreadPool();

    public static void main(String[] args) {
        System.out.println("Сервер запущен на порту " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket socket = serverSocket.accept();
                threadPool.execute(new ClientHandler(socket));
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            threadPool.shutdown();
        }
    }

    public static void broadcast(String message) {
        for (ClientHandler client : onlineUsers.values()) {
            client.sendMessage(message);
        }
    }

    public static void addUser(String username, ClientHandler client) {
        onlineUsers.put(username, client);
        broadcast("SERVER: " + username + " присоединился к чату.");
    }

    public static void removeUser(String username) {
        if (username != null) {
            onlineUsers.remove(username);
            broadcast("SERVER: " + username + " покинул чат.");
        }
    }

    public static String getOnlineUsers() {
        return String.join(", ", onlineUsers.keySet());
    }
}

class ClientHandler implements Runnable {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private String username;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            authenticate();
            out.println("\nДобро пожаловать в чат, " + username + "!");
            out.println("Доступные команды:");
            out.println("/users - список пользователей");
            out.println("/exit - выйти из чата\n");

            String message;
            while ((message = in.readLine()) != null) {
                if (message.equalsIgnoreCase("/exit")) break;
                if (message.equalsIgnoreCase("/users")) {
                    out.println("Онлайн: " + Server.getOnlineUsers());
                } else {
                    Server.broadcast(username + ": " + message);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            shutdown();
        }
    }
    private void authenticate() throws IOException {
        while (true) {
            out.println("Введите 1 для регистрации или 2 для входа:");
            String choice = in.readLine();
            if ("1".equals(choice)) {
                out.println("Регистрация: введите логин:");
                String login = in.readLine();
                out.println("Введите пароль:");
                String password = in.readLine();
                // Упрощенная проверка без базы данных
                if (!login.isEmpty() && !password.isEmpty()) {
                    this.username = login;
                    out.println("Регистрация успешна!");
                    Server.addUser(username, this);
                    break;
                } else {
                    out.println("Ошибка: Логин/пароль не могут быть пустыми.");
                }
            } else if ("2".equals(choice)) {
                out.println("Вход: введите логин:");
                String login = in.readLine();
                out.println("Введите пароль:");
                String password = in.readLine();
                // Упрощенная проверка без базы данных
                if (!login.isEmpty() && !password.isEmpty()) {
                    this.username = login;
                    out.println("Вход успешен!");
                    Server.addUser(username, this);
                    break;
                } else {
                    out.println("Ошибка входа. Проверьте логин/пароль.");
                }
            } else {
                out.println("Неверная команда.");
            }
        }
    }

    private void shutdown() {
        try {
            Server.removeUser(username);
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String message) {
        out.println(message);
    }
}