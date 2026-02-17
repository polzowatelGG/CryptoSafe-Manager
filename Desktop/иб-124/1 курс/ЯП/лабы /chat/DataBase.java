import java.io.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DataBase {
    // Храним пользователей в потокобезопасной коллекции ConcurrentHashMap
    private static final Map<String, String> users = new ConcurrentHashMap<>();
    private static final String FILE_PATH = "users.txt";  // Путь к файлу для хранения пользователей

    // Статический блок инициализации для загрузки пользователей из файла при старте программы
    static {
        loadUsersFromFile();
    }

    // Метод регистрации нового пользователя
    public static synchronized boolean registerUser(String username, String password) {
        // Проверяем, существует ли уже пользователь с таким логином
        if (users.containsKey(username)) {
            return false;  // Если да, то возвращаем false (регистрация не удалась)
        }
        // Добавляем нового пользователя
        users.put(username, password);
        // Сохраняем пользователей в файл
        saveUsersToFile();
        return true;  // Возвращаем true, если регистрация прошла успешно
    }

    // Метод для входа пользователя
    public static synchronized boolean loginUser(String username, String password) {
        // Проверяем, совпадает ли введенный пароль с сохраненным в базе
        return password.equals(users.get(username));
    }

    // Метод для загрузки пользователей из файла
    private static synchronized void loadUsersFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_PATH))) {
            String line;
            while ((line = reader.readLine()) != null) {  // Читаем файл построчно
                String[] parts = line.split(":");  // Разделяем строку на логин и пароль
                if (parts.length == 2) {
                    // Добавляем пользователя в коллекцию
                    users.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            System.err.println("Ошибка при загрузке пользователей из файла: " + e.getMessage());
        }
    }

    // Метод для сохранения пользователей в файл
    private static synchronized void saveUsersToFile() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_PATH))) {
            for (Map.Entry<String, String> entry : users.entrySet()) {
                // Записываем логин и пароль каждого пользователя в файл
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();  // Переходим на новую строку
            }
        } catch (IOException e) {
            System.err.println("Ошибка при сохранении пользователей в файл: " + e.getMessage());
        }
    }
}
