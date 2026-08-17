"""DNS enumaration.
Resolves common record types for a traget domain using a dnspython.
Each lookup is independent and failures for one recond type never
abort the others.
"""

from __future__ import annotations

from typing import Dict, List

import dns.resolver

RECORD_TYPES: List[str] = ["A","AAAA", "MX" , "NS" , "TXT" , "CNAME" , "SOA" ]


def _resolve(domain: str,  record_type: str, timeout: float) -> List[str]:
  try:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    answers = resolver.resolve(domain, record_type)
    return [answer.to_text().strip() for answer in answers ]
  except (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.NoNameServers,
    dns.exception.Timeout,
  ):
    return[]
  except Exception;
  #Any unexcepted resolver error should not crash the scan
  return[]

  def enumerate)dns(domain:str, timeout:float = 5.0) -> Dict{str, List[str]]:
  """Return a mapping of record type -> list of values for the domain"""
  results: Dict[str, List[str]] = {}
  for record_type in RECORD_TYPES:
    values = _resolve(domain, record_type, timeout)
    if values:
      results[record_type] = values
      return results
    
