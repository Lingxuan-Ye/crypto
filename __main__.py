try:
    from .src.main import main  # for 'python -m crypto', which is recommended
except ImportError:
    from src.main import main  # for 'python crypto'

if __name__ == "__main__":
    main()
