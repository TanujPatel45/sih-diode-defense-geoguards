import type { Metadata } from "next";
import { Geist, Geist_Mono, Inter } from "next/font/google";
import "./globals.css";
import { Sidebar } from "./components/Sidebar";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700", "800"],
});

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "GeoGuards — Passive Cyber Intelligence",
  description:
    "GeoGuards: Passive, metadata-driven threat detection for unidirectional networks. " +
    "SIH 2026 Problem Statement 26145. No active response — passive monitoring only.",
  keywords: ["GeoGuards", "NIDS", "passive monitoring", "data diode", "SIH 26145", "cyber intelligence"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${geistSans.variable} ${geistMono.variable} h-full`}
    >
      <body
        style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "row",
          background: "var(--gg-bg)",
          color: "var(--gg-text)",
        }}
      >
        <Sidebar />
        <main style={{ flex: 1, minWidth: 0, overflowY: "auto", display: "flex", flexDirection: "column" }}>
          {children}
        </main>
      </body>
    </html>
  );
}
