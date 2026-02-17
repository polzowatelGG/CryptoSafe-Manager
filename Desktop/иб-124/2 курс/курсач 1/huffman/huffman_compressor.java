import java.io.*;
import java.nio.file.*;
import java.util.*;

public class huffman_compressor{

    // Класс для узлов дерева Хаффмана
    static class Node {
        char ch;
        int freq;
        Node left;
        Node right;

        Node(char ch, int freq) {
            this.ch = ch;
            this.freq = freq;
        }

        Node(int freq, Node left, Node right) {
            this.ch = '\0';
            this.freq = freq;
            this.left = left;
            this.right = right;
        }

        boolean isLeaf() {
            return left == null && right == null;
        }
    }

    public static void main(String[] args) {
        CreationNewFile("//Users/gleb-djan/Desktop/иб-124/2 курс/курсач 1/тест хаффман/test1.txt");  //ссылка на файл который будет сканировать
    }

    // Построение дерева Хаффмана
    public static Node BuildHuffmanTree(Map<Character, Integer> freqMap) {
        PriorityQueue<Node> heap = new PriorityQueue<>(Comparator.comparingInt(n -> n.freq));

        for (var entry : freqMap.entrySet()) {
            heap.add(new Node(entry.getKey(), entry.getValue()));
        }

        while (heap.size() > 1) {
            Node left = heap.poll();
            Node right = heap.poll();
            heap.add(new Node(left.freq + right.freq, left, right));
        }

        return heap.poll();
    }

    // Генерация бинарных кодов для символов
    public static void GenerateCodes(Node node, String prefix, Map<Character, String> codes) {
        if (node == null) return;

        if (node.isLeaf()) {
            codes.put(node.ch, prefix);
            return;
        }

        GenerateCodes(node.left, prefix + "0", codes);
        GenerateCodes(node.right, prefix + "1", codes);
    }

    // Перевод битовой строки в массив байтов
    public static byte[] packBitsToBytes(String bitString) {
        int bitLength = bitString.length();
        int byteLength = (bitLength + 7) / 8;
        byte[] bytes = new byte[byteLength];

        for (int i = 0; i < bitLength; i++) {
            if (bitString.charAt(i) == '1') {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        return bytes;
    }

    // Запись закодированного файла в бинарном виде
    public static void writeEncodedFile(String bitString, Map<Character, String> codes, Path filePath) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(filePath))) {

            // 1. Количество уникальных символов
            dos.writeByte(codes.size());

            // 2. Таблица символов и длина их кода
            for (var entry : codes.entrySet()) {
                dos.writeChar(entry.getKey());
                dos.writeByte(entry.getValue().length());
            }

            // 3. Сами коды символов побитово
            for (var entry : codes.entrySet()) {
                byte[] codeBytes = packBitsToBytes(entry.getValue());
                dos.write(codeBytes);
            }

            // 4. Длина закодированного текста в битах
            dos.writeInt(bitString.length());

            // 5. Закодированные данные
            dos.write(packBitsToBytes(bitString));
        }
    }

    // Основная функция: создание нового бинарного файла
    public static void CreationNewFile(String filePatch) {
        String text = "";
        try {
            text = Files.readString(Paths.get(filePatch));
        } catch (IOException e) {
            System.err.println("ошибка при чтении файла: " + e.getMessage());
            return;
        }

        if (text.isEmpty()) {
            System.err.println("файл пустой");
            return;
        }

        // Подсчет частот символов
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : text.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }

        System.out.println("уникальные символы: " + freqMap);

        Node root = BuildHuffmanTree(freqMap);

        Map<Character, String> codes = new HashMap<>();
        GenerateCodes(root, "", codes);

        System.out.println("\nбинарные коды символов:");
        for (var e : codes.entrySet()) {
            System.out.println(e.getKey() + " : " + e.getValue());
        }

        StringBuilder codedText = new StringBuilder();
        for (char c : text.toCharArray()) {
            codedText.append(codes.get(c));
        }

        System.out.println("закодированный текст (первые 100 бит): " +
                (codedText.length() > 100 ? codedText.substring(0, 100) + "..." : codedText));

        try {
            Path originalPath = Paths.get(filePatch);
            String encodedFileName = "encoded_" + originalPath.getFileName().toString().replaceAll("\\.txt$", ".bin");
            Path encodedFilePath = originalPath.getParent().resolve(encodedFileName);

            writeEncodedFile(codedText.toString(), codes, encodedFilePath);

            long originalSize = Files.size(originalPath);
            long encodedSize = Files.size(encodedFilePath);

            System.out.println("\n=== РЕЗУЛЬТАТЫ СЖАТИЯ ===");
            System.out.println("исходный размер: " + originalSize + " байт");
            System.out.println("закодированный размер: " + encodedSize + " байт");
            System.out.println("сжатый файл меньше исходного в " + String.format("%.2f", (double) originalSize / encodedSize) + " раз(а)");
            System.out.println(encodedSize < originalSize ? "СЖАТИЕ ПРОШЛО УСПЕШНО!" : "СЖАТИЕ НЕЭФФЕКТИВНО");

            System.out.println("закодированный файл: " + encodedFilePath);

        } catch (IOException e) {
            System.err.println("ошибка при записи файла: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
 