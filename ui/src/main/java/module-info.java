module pl.jrkm.ui {
    requires javafx.controls;
    requires javafx.fxml;
    requires pl.jrkm.encryption;

    opens pl.jrkm.ui to javafx.fxml;
    exports pl.jrkm.ui;
}