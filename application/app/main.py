import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout
from PyQt6.QtCore import Qt

def main():
    # 1. Create the application instance
    app = QApplication(sys.argv)

    # 2. Create the main window
    window = QWidget()
    window.setWindowTitle("PyQt6 Centered Button")
    window.resize(400, 300)

    # 3. Create a layout and center its alignment
    layout = QVBoxLayout()
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    # 4. Create the button and add it to the layout
    button = QPushButton("Start Analysis")
    button.setFixedSize(120, 40)
    layout.addWidget(button)

    # 5. Set the layout on the window and show it
    window.setLayout(layout)
    window.show()

    # 6. Start the event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()