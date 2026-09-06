import os

try:
    import chromadb
    from chromadb.utils import embedding_functions

    # Use absolute path relative to this file for stability across cwd
    _db_path = os.path.join(os.path.dirname(__file__), "chroma_db")
    client = chromadb.PersistentClient(path=_db_path)
    embedding_fn = embedding_functions.DefaultEmbeddingFunction()
    collection = client.get_or_create_collection(
        name="episode_transcripts",
        embedding_function=embedding_fn
    )
    _chroma_available = True
except Exception as e:
    print(f"[memory] chromadb unavailable, using in-memory fallback: {e}")
    client = None
    collection = None
    _chroma_available = False
    _memory_fallback: list = []

def store_episode_memory(episode_id: str, attack_target: str, endpoint: str, finding: str, mitigation: str):
    doc_text = f"Episode: {episode_id}\nAttack Type: {attack_target}\nTarget Endpoint: {endpoint}\nObservation: {finding}\nMitigation Applied: {mitigation}"
    if not _chroma_available or collection is None:
        try:
            _memory_fallback.append(doc_text)
            # keep last 50
            if len(_memory_fallback) > 50:
                _memory_fallback.pop(0)
        except Exception:
            pass
        return
    try:
        collection.upsert(
            documents=[doc_text],
            metadatas=[{
                "episode_id": episode_id,
                "attack_target": attack_target,
                "endpoint": endpoint
            }],
            ids=[episode_id]
        )
    except Exception as e:
        print(f"[memory] store failed: {e}")
        try:
            _memory_fallback.append(doc_text)
        except Exception:
            pass

def retrieve_past_context(query: str, n_results: int = 2) -> str:
    if not _chroma_available or collection is None:
        if '_memory_fallback' in globals() and _memory_fallback:
            return "\n---\n".join(_memory_fallback[-n_results:])
        return "No prior episode records available."
    try:
        results = collection.query(
            query_texts=[query],
            n_results=n_results
        )
        if not results["documents"] or not results["documents"][0]:
            return "No prior episode records available."
        return "\n---\n".join(results["documents"][0])
    except Exception as e:
        print(f"[memory] retrieve failed: {e}")
        return "No prior episode records available."