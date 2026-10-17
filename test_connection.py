
import os
import sys

from dotenv import load_dotenv
from falkordb import FalkorDB


def check_connection() -> int:
    """Attempt a live FalkorDB connectivity check.

    Returns 0 on success and 1 on failure. No credentials are printed.
    """
    try:
        load_dotenv()

        db = FalkorDB(
            host=os.environ["FALKORDB_HOST"],
            port=int(os.getenv("FALKORDB_PORT", "54211")),
            username=os.environ["FALKORDB_USERNAME"],
            password=os.environ["FALKORDB_PASSWORD"],
            ssl=False,
            socket_connect_timeout=5,
            socket_timeout=5,
        )

        graph_name = os.getenv("FALKORDB_GRAPH", "eclipse-ai")
        graph = db.select_graph(graph_name)

        result = graph.query(
            "MATCH (n) RETURN count(n) AS node_count"
        )
    except KeyError as exc:
        print(f"Eclipse AI database connection: FAILED (missing variable: {exc.args[0]})")
        return 1
    except Exception as exc:
        print(f"Eclipse AI database connection: FAILED ({type(exc).__name__})")
        return 1

    print("Eclipse AI database connection: SUCCESS")
    print("Graph:", graph_name)
    print("Node count:", result.result_set[0][0])
    return 0


def main() -> int:
    return check_connection()


if __name__ == "__main__":
    sys.exit(main())
