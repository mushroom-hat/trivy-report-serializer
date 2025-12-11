def parse_image_info(body):
  '''
    Parse image information from the trivy webhook payload.
  '''
  report = body["report"]
  artifact = report["artifact"]
  return {
      "digest": artifact["digest"],
      "path": artifact["repository"],
      "tag": artifact.get("tag", "latest"),
      "registry": report["registry"]["server"],
      "os_family": report["os"].get("family"),
      "os_name": report["os"].get("name"),
  }
