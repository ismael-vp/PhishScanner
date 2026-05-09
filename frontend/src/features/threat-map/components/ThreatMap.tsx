"use client";

import React from 'react';
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

// TopoJSON simplificado del mundo
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export interface ThreatMapProps {
  lat: number;
  lon: number;
  label?: string;
  isp?: string;
}

export default function ThreatMap({ lat, lon, label, isp }: ThreatMapProps) {
  return (
    <div className="w-full h-full bg-[#050505] rounded-md overflow-hidden flex items-center justify-center border border-[#333] relative">
      <div className="absolute top-4 left-4 z-10 flex items-center space-x-3">
        <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>
        <span className="text-sm font-mono text-[#888]">LIVE TRACKING</span>
      </div>

      <div className="absolute bottom-4 right-4 z-10 bg-black/60 backdrop-blur-sm border border-[#333] rounded-md p-3 flex flex-col font-mono text-xs text-[#ededed]">
        <div className="flex space-x-2"><span className="text-[#888]">LAT:</span><span>{lat.toFixed(4)}</span></div>
        <div className="flex space-x-2"><span className="text-[#888]">LNG:</span><span>{lon.toFixed(4)}</span></div>
        {isp && (
          <div className="flex space-x-2 mt-1 pt-1 border-t border-[#333]">
            <span className="text-[#888]">ISP:</span>
            <span className="truncate max-w-[120px]" title={isp}>{isp}</span>
          </div>
        )}
      </div>

      <ComposableMap 
        projection="geoMercator" 
        projectionConfig={{ scale: 120 }}
        width={800}
        height={400}
        style={{ width: "100%", height: "100%" }}
      >
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography 
                key={geo.rsmKey} 
                geography={geo} 
                fill="#111111" 
                stroke="#333333"
                strokeWidth={0.5}
                style={{
                  default: { outline: "none" },
                  hover: { outline: "none" },
                  pressed: { outline: "none" },
                }}
              />
            ))
          }
        </Geographies>
        
        {/* Marcador en la posición exacta — sin animate-ping para no forzar repaints continuos */}
        <Marker coordinates={[lon, lat]}>
          {/* Halo estático: no usa animación CSS para evitar repaints en SVG */}
          <circle r={14} fill="#ef4444" opacity={0.15} />
          <circle r={6} fill="#ef4444" stroke="#000" strokeWidth={1.5} />
          
          {label && (
            <text
              textAnchor="middle"
              y={-18}
              style={{ fontFamily: "system-ui", fill: "#ededed", fontSize: "14px", fontWeight: 500 }}
            >
              {label}
            </text>
          )}
        </Marker>
      </ComposableMap>
    </div>
  );
}

