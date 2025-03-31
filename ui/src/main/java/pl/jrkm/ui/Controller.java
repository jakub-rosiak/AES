package pl.jrkm.ui;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import pl.jrkm.encryption.Aes;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class Controller {

    @FXML
    public TextField keyField;

    @FXML
    public TextArea leftTextArea;

    @FXML
    public TextArea RightTextArea;
;
    @FXML
    public void handleEncrypt(ActionEvent actionEvent) {
        String text = leftTextArea.getText();
        String key = keyField.getText();
        String encrypted = Aes.encrypt(text, key);
        RightTextArea.setText(encrypted);
    }

    public void handleDecrypt(ActionEvent actionEvent) {
        String text = RightTextArea.getText();
        String key = keyField.getText();
        String decrypted = Aes.decrypt(text, key);
        leftTextArea.setText(decrypted);
    }

    public void handleEncryptFile(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open a text file");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            String fileContent = readFile(file);
            leftTextArea.setText(fileContent);
        }
    }

    private String readFile(File file) {
        StringBuilder content = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return content.toString();
    }

    public void handleDecryptFile(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open a text file");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            String fileContent = readFile(file);
            RightTextArea.setText(fileContent);
        }
    }

    public void handleClear(ActionEvent actionEvent) {
    }
}