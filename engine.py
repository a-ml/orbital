# import vertexai
# from vertexai import agent_engines

# vertexai.init(
#     project="ombo-409308",
#     location="us-central1",
#     staging_bucket="gs://onzo_agent_hub",
# )
# # Create an agent engine instance
# agent_engine = agent_engines.create()

import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
load_dotenv()
import os

# TODO(developer): Update and un-comment below line
# PROJECT_ID = "your-project-id"
vertexai.init(project=os.getenv("PROJECT_ID"), location="us-central1")
#PROJECT_ID, location="us-central1")

reasoning_engine_list = reasoning_engines.ReasoningEngine.list()
print(reasoning_engine_list)
# Example response:
# [<vertexai.reasoning_engines._reasoning_engines.ReasoningEngine object at 0x71a0e5cb99c0>
# resource name: projects/123456789/locations/us-central1/reasoningEngines/111111111111111111,
# <vertexai.reasoning_engines._reasoning_engines.ReasoningEngine object at 0x71a0e5cbac80>
# resource name: projects/123456789/locations/us-central1/reasoningEngines/222222222222222222]