//        AES
//        Copyright (C) Jakub Rosiak, Krzysztof Miller
//
//        This program is free software: you can redistribute it and/or modify
//        it under the terms of the GNU General Public License as published by
//        the Free Software Foundation, either version 3 of the License, or
//        (at your option) any later version.
//
//        This program is distributed in the hope that it will be useful,
//        but WITHOUT ANY WARRANTY; without even the implied warranty of
//        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//        GNU General Public License for more details.
//
//        You should have received a copy of the GNU General Public License
//        along with this program.  If not, see <http://www.gnu.org/licenses/>.

package pl.jrkm.ui;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import pl.jrkm.encryption.Aes;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class Controller {

    @FXML
    public TextField keyField;

    @FXML
    public TextArea leftTextArea;

    @FXML
    public TextArea rightTextArea;

    @FXML
    public ComboBox<String> keySizeComboBox;

    @FXML
    public Label statusLabel;
;
    @FXML
    public void handleEncrypt(ActionEvent actionEvent) {
        statusLabel.setText("Encrypting...");
        String text = leftTextArea.getText();
        String key = keyField.getText();
        if (key.length() % 2 != 0) {
            statusLabel.setText("Invalid Key Length");
            return;
        }
        byte[] plainTextBytes = text.getBytes(StandardCharsets.UTF_8);
        int[] keyInts = stringToHexArray(key);
        if (keyInts.length != 16 && keyInts.length != 24 && keyInts.length != 32) {
            statusLabel.setText("Invalid Key Length");
            return;
        }
        int[] plainTextInts = new int[plainTextBytes.length];
        for (int i = 0; i < plainTextBytes.length; i++) {
            plainTextInts[i] = plainTextBytes[i] & 0xFF;
        }
        try {
            int[] encrypted = Aes.encrypt(plainTextInts, keyInts);
            rightTextArea.setText(hexToString(encrypted));
            statusLabel.setText("Encryption Successful");
        } catch (Exception e) {
            statusLabel.setText("Encryption Failed");
        }
    }

    public void handleDecrypt(ActionEvent actionEvent) {
        statusLabel.setText("Decrypting...");
        String text = rightTextArea.getText();
        String key = keyField.getText();
        if (key.length() % 2 != 0) {
            statusLabel.setText("Invalid Key Length");
            return;
        }
        int[] keyInts = stringToHexArray(key);
        if (keyInts.length != 16 && keyInts.length != 24 && keyInts.length != 32) {
            statusLabel.setText("Invalid Key Length");
            return;
        }
        int[] encryptedInts = stringToHexArray(text);
        try {
            int[] decrypted = Aes.decrypt(encryptedInts, keyInts);
            leftTextArea.setText(toUtf8String(decrypted));
            statusLabel.setText("Decryption Successful");
        } catch (Exception e) {
            statusLabel.setText("Decryption Failed");
        }
    }

    public void handleEncryptFile(ActionEvent actionEvent) {
        statusLabel.setText("Encrypting File...");
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            byte[] fileContent = readFile(file);
            String key = keyField.getText();
            if (key.length() % 2 != 0) {
                statusLabel.setText("Invalid Key Length");
                return;
            }
            int[] keyInts = stringToHexArray(key);
            if (keyInts.length != 16 && keyInts.length != 24 && keyInts.length != 32) {
                statusLabel.setText("Invalid Key Length");
                return;
            }

            int[] fileInts = new int[fileContent.length];
            for (int i = 0; i < fileContent.length; i++) {
                fileInts[i] = fileContent[i] & 0xFF;
            }
            try {
                int[] encrypted = Aes.encrypt(fileInts, keyInts);

                FileChooser fileChooser1 = new FileChooser();
                File file1 = fileChooser1.showSaveDialog(null);
                if (file1 != null) {
                    saveBytesToFile(file1, encrypted);
                    statusLabel.setText("Encryption Successful");
                    return;
                }
            } catch (Exception e) {
                statusLabel.setText("Encryption Failed");
                return;
            }
        }
        statusLabel.setText("File not selected");
    }

    private byte[] readFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    private void saveBytesToFile(File file, int[] fileContent) {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file))) {
            for (int i : fileContent) {
                bos.write(i);
            }
            bos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void handleDecryptFile(ActionEvent actionEvent) {
        statusLabel.setText("Decrypting File...");
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            byte[] fileContent = readFile(file);
            String key = keyField.getText();
            if (key.length() % 2 != 0) {
                statusLabel.setText("Invalid Key Length");
                return;
            }
            int[] keyInts = stringToHexArray(key);
            if (keyInts.length != 16 && keyInts.length != 24 && keyInts.length != 32) {
                statusLabel.setText("Invalid Key Length");
                return;
            }

            int[] encryptedInts = new int[fileContent.length];
            for (int i = 0; i < fileContent.length; i++) {
                encryptedInts[i] = fileContent[i] & 0xFF;
            }

            try {
                int[] decrypted = Aes.decrypt(encryptedInts, keyInts);

                FileChooser fileChooser1 = new FileChooser();
                File file1 = fileChooser1.showSaveDialog(null);
                if (file1 != null) {
                    saveBytesToFile(file1, decrypted);
                    statusLabel.setText("Decryption Successful");
                    return;
                }
            } catch (Exception e) {
                statusLabel.setText("Decryption Failed");
                return;
            }
        }
        statusLabel.setText("File not selected");
    }

    public void handleGenerateKey(ActionEvent actionEvent) {
        statusLabel.setText("Generating Key...");
        String selectedKey = keySizeComboBox.getSelectionModel().getSelectedItem();
        if (selectedKey != null) {
            keyField.setText(generateKey(Integer.parseInt(selectedKey.split(" ")[0])));
            statusLabel.setText("Key Generation Successful");
            return;
        }
        statusLabel.setText("Key Generation Failed");
    }

    public String generateKey(int length) {
        int byteLength = length / 8;
        int[] keyBytes = new int[byteLength];
        Random random = new Random();

        for (int i = 0; i < byteLength; i++) {
            keyBytes[i] = random.nextInt(256);
        }

        return hexToString(keyBytes);
    }

    public void handleLoadKeyFromFile(ActionEvent actionEvent) {
        statusLabel.setText("Loading Key...");
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            try {
                keyField.setText(Files.readString(Paths.get(file.getAbsolutePath())).trim());
                statusLabel.setText("Key Loaded Successfully");
            } catch (IOException e) {
                statusLabel.setText("Error Loading Key");
            }
            return;
        }
        statusLabel.setText("Error Loading Key");
    }

    public void handleSaveKeyToFile(ActionEvent actionEvent) {
        statusLabel.setText("Saving Key...");
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showSaveDialog(null);
        if (file != null) {
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(keyField.getText());
                statusLabel.setText("Key Saved Successfully");
            } catch (IOException e) {
                statusLabel.setText("Error Saving Key");
            }
            return;
        }
        statusLabel.setText("Error Saving Key");
    }

    static int[] stringToHexArray(String hex) {
        int[] intArray = new int[hex.length() / 2];
        for (int i = 0; i < hex.length(); i+=2) {
            intArray[i/2] = Integer.parseInt(hex. substring(i, i+2), 16);
        }
        return intArray;
    }

    static String hexToString(int[] intArray) {
        StringBuilder sb = new StringBuilder();

        for (int val: intArray) {
            sb.append(String.format("%02X", val));
        }

        return sb.toString();
    }

    static String toUtf8String(int[] intArray) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        for (int val : intArray) {
            System.out.printf("%02X", val);
            baos.write(val & 0xFF);
        }

        byte[] rawBytes = baos.toByteArray();

        if (rawBytes.length > 0) {
            int paddingLength = rawBytes[rawBytes.length - 1] & 0xFF;

            if (paddingLength > 0 && paddingLength <= 16) {
                boolean validPadding = true;
                for (int i = rawBytes.length - paddingLength; i < rawBytes.length; i++) {
                    if ((rawBytes[i] & 0xFF) != paddingLength) {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding) {
                    rawBytes = Arrays.copyOfRange(rawBytes, 0, rawBytes.length - paddingLength);
                }
            }
        }

        try {
            return new String(rawBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert decrypted data to UTF-8 string", e);
        }
    }
}