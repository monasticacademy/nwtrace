'use client'

import Image from "next/image";
import styles from "./page.module.css";
import { useEffect, useState } from "react";

type Request = {
  method: string;
  url: string;
};

type Response = {
  status: string;
  size: number;
};

type Call = {
  request: Request;
  response: Response;
};

export type Calls = Call[];

export default function Home() {
  const [calls, setCalls] = useState<Calls>([]);

  // useEffect means react will run the inner function once whenever the listed dependencies change
  useEffect(() => {
    const stream = new EventSource('http://localhost:5000/api/calls');
    stream.onmessage = (event) => {
      const payload: Call = JSON.parse(event.data);
      console.log(payload);
      setCalls((calls) => [...calls, payload]);
    };
    stream.onerror = (err) => {
      console.error("error reading calls from backend:", err);
    };
    return () => stream.close();
  }, []);

  return (
    <main>
      <menu>
        <button className="selected">All</button>
        <button>JSON</button>
        <button>XML</button>
        <button>HTML</button>
        <button>CSS</button>
        <button>JS</button>
        <button>Images</button>
        <button>WS</button>
        <button>Other</button>
      </menu>
      <table>
        <thead>
          <tr>
            <td>Status</td>
            <td>Method</td>
            <td>Domain</td>
            <td>File</td>
            <td>Type</td>
            <td>Transferred</td>
            <td>Size</td>
          </tr>
        </thead>
        <tbody>
          {calls.map(call => (
            <tr>
              <td>{call.response.status}</td>
              <td>{call.request.method}</td>
              <td>localhost:3000</td>
              <td>layout.css</td>
              <td>JSON</td>
              <td>373 kB</td>
              <td>{call.response.size}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
