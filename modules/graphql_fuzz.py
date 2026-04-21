import json


class GraphQLFuzzModule:
    name = "graphql_fuzz"
    severity = "medium"

    async def run(self, target, session, context):
        findings = []

        endpoint = f"{target}/graphql"

        introspection_query = {"query": """
            query IntrospectionQuery {
              __schema {
                types {
                  name
                }
              }
            }
            """}

        try:
            r = await session.post(endpoint, json=introspection_query)

            if "__schema" in r.text:
                findings.append(
                    {
                        "type": "GraphQL",
                        "issue": "Introspection enabled",
                        "endpoint": endpoint,
                    }
                )
        except:
            pass

        return findings
