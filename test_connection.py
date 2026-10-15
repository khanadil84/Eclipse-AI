
import os
from dotenv import load_dotenv
from falkordb import FalkorDB

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

print("Eclipse AI database connection: SUCCESS")
print("Graph:", graph_name)
print("Node count:", result.result_set[0][0])
