import { Bricolage_Grotesque, Outfit, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// Fonts from design.md §3: display / body / mono.
const display = Bricolage_Grotesque({ subsets: ["latin"], weight: ["800"], variable: "--font-display" });
const body = Outfit({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-body" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "600"], variable: "--font-mono" });

export const metadata = {
  title: "CodeGuard",
  description: "Pre-execution safety check for AI-generated code",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
