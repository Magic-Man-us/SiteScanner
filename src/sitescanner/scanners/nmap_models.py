"""Pydantic models for Nmap XML parsing.

These models provide a small validated structure for parsed nmap XML output.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from pydantic import BaseModel, Field


class ServiceModel(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None


class PortModel(BaseModel):
    portid: int
    protocol: str
    state: str
    service: ServiceModel | None = None


class HostModel(BaseModel):
    address: str
    ports: list[PortModel] = Field(default_factory=list)


class NmapRunModel(BaseModel):
    hosts: list[HostModel] = Field(default_factory=list)

    @classmethod
    def from_xml(cls, xml_text: str) -> NmapRunModel:
        """Parse nmap XML text into models.

        This is intentionally small and tolerant: unknown/missing fields are
        set to None where possible.
        """
        root = ET.fromstring(xml_text)
        hosts: list[HostModel] = []

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            addr = addr_el.get("addr") if addr_el is not None else ""

            ports_el = host_el.find("ports")
            ports: list[PortModel] = []
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    try:
                        portid = int(port_el.get("portid") or 0)
                    except ValueError:
                        portid = 0

                    protocol = port_el.get("protocol") or "tcp"
                    state_el = port_el.find("state")
                    state = (state_el.get("state") if state_el is not None else None) or "unknown"

                    service_el = port_el.find("service")
                    service = None
                    if service_el is not None:
                        service = ServiceModel(
                            name=service_el.get("name"),
                            product=service_el.get("product"),
                            version=service_el.get("version"),
                        )

                    ports.append(
                        PortModel(portid=portid, protocol=protocol, state=state, service=service)
                    )

            hosts.append(HostModel(address=addr or "", ports=ports))

        return cls(hosts=hosts)
