import argparse

import uvicorn

from .app import create_app


def main():
    parser = argparse.ArgumentParser(prog="shadow_rules")
    parser.add_argument("--port", type=int, default=5215)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db", default="shadow_rules.db")
    args = parser.parse_args()
    uvicorn.run(create_app(db_path=args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
