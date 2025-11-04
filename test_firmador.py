import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock
from firmador_moderno import FirmaController

class TestFirmaController(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config = {
            'SIA': {'dir_temp': self.test_dir},
            'PKCS11': {}
        }
        self.datos_sia = {}
        self.archivos_a_firmar = []
        self.pin_token = "1234"
        self.status_callback = MagicMock()

        self.controller = FirmaController(
            self.config,
            self.datos_sia,
            self.archivos_a_firmar,
            self.pin_token,
            self.status_callback
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_limpiar_temp(self):
        # Create dummy files in the temporary directory
        (Path(self.test_dir) / "file1.txt").touch()
        (Path(self.test_dir) / "file2.pdf").touch()

        # Ensure files exist before calling the method
        self.assertEqual(len(list(Path(self.test_dir).glob('*'))), 2)

        # Call the method to be tested
        self.controller._limpiar_temp()

        # Assert that the directory is now empty
        self.assertEqual(len(list(Path(self.test_dir).glob('*'))), 0)

if __name__ == '__main__':
    unittest.main()
