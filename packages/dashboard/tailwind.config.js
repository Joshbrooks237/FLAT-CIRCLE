/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#000000",
        slime: {
          50:  "#e6fff4",
          100: "#b3ffe0",
          200: "#66ffc0",
          300: "#00f07a",  // core glow
          400: "#00cc66",
          500: "#009950",
          600: "#00703a",
          700: "#004d28",
          800: "#002a16",
          900: "#001209",
        },
        threat: {
          low:    "#00f07a",
          medium: "#f0a500",
          high:   "#f04a00",
          nation: "#cc0033",
        },
      },
      fontFamily: {
        display: ["'DM Serif Display'", "Georgia", "serif"],
        mono:    ["'JetBrains Mono'", "'Fira Code'", "Consolas", "monospace"],
      },
      animation: {
        "pulse-slow":   "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "pulse-fast":   "pulse 0.8s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "breathe":      "breathe 6s ease-in-out infinite",
        "slime-flow":   "slimeFlow 8s linear infinite",
        "ripple":       "ripple 1.2s ease-out forwards",
        "flare":        "flare 0.6s ease-out forwards",
        "thicken":      "thicken 2s ease-in-out forwards",
        "scroll-up":    "scrollUp 0.3s ease-out forwards",
      },
      keyframes: {
        breathe: {
          "0%, 100%": { opacity: "0.6", transform: "scale(1)" },
          "50%":       { opacity: "0.9", transform: "scale(1.015)" },
        },
        slimeFlow: {
          "0%":   { "background-position": "0% 50%" },
          "100%": { "background-position": "100% 50%" },
        },
        ripple: {
          "0%":   { transform: "scale(0.8)", opacity: "0.9" },
          "100%": { transform: "scale(2.5)", opacity: "0" },
        },
        flare: {
          "0%":   { opacity: "1", filter: "brightness(3)" },
          "100%": { opacity: "0.7", filter: "brightness(1)" },
        },
        thicken: {
          "0%":   { opacity: "0.5", filter: "blur(0px)" },
          "50%":  { opacity: "0.85", filter: "blur(0.5px)" },
          "100%": { opacity: "0.7", filter: "blur(0px)" },
        },
        scrollUp: {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
