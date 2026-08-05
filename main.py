"""Точка входа для запуска из исходников: делегирует CLI uniconn."""


def main():
    from uniconn.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
