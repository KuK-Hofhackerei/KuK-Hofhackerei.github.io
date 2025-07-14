export const SITE_TITLE = "KuK Hof\u00ADhackerei";
export const SITE_DESCRIPTION =
  `KuK Hofhackerei is Austria's CTF merger team. We participate in CTF events from around the world with our member teams We_0wn_y0u, LosFuzzys, SIGFLAG, /dev/stp and Team Austria.`;

export const MEMBER_TEAMS = [
  {"name": "We_0wn_y0u", "link": "https://w0y.at/"},
  {"name": "LosFuzzys", "link": "https://losfuzzys.net/"},
  {"name": "SIGFLAG", "link": "https://sigflag.at/"},
  {"name": "/dev/stp", "link": "https://www.fhstp.ac.at/de/studium/informatik-security/it-security"}, // TODO add proper link
  {"name": "Team Austria", "link": "https://acsc.land/team-at/"},
];
export const ABOUT_ME =
  `KuK Hofhackerei is a collective of Austrian cybersecurity talents, drawing from top universities such as TU Wien, University of Vienna, JKU, TU Graz and FH St. Pölten. In the annual DEF CON CTF Qualifiers, we proudly secured 6th place out of more than a thousand elite teams worldwide. This achievement grants us the privilege to compete onsite at the DEF CON Finals during the prestigious conference in Las Vegas.`;
export const GITHUB_USERNAME = "KuK-Hofhackerei";
export const QUOTE = "Austria's CTF Merger Team";
export const NAV_LINKS: Array<{ title: string; href?: string }> = [
  {
    title: "CTFtime",
    href: "//ctftime.org/team/59774",
  },
  {
    title: "X",
    href: "//x.com/kukhofhackerei",
  },
  {
    title: "Bluesky",
    href: "//bsky.app/profile/did:plc:yawykwgqdwpuua47fgtyjcja",
  },
  {
    title: "Blog",
  },
];
import dynatrace from "@/assets/dynatrace.png";
import erstebank from "@/assets/erstebank.svg";
import bosch from "@/assets/bosch.svg";
import siemens from "@/assets/siemens.svg";
import tuwien from "@/assets/cysec.svg";
import tugraz from "@/assets/tugraz.svg";
import sba from "@/assets/sba.svg";
import fhstp from "@/assets/fhstp.svg";
import jku from "@/assets/jku.svg";

import type { ImageMetadata } from "astro";
export const SUPPORTERS: { [tier: string]: Array<{ name: string; image: ImageMetadata; imageClasses?: string; href: string }> } = {
  "Platinum":
    [
      {
        name: "dynatrace",
        image: dynatrace,
        href: "https://www.dynatrace.com/",
      },
      {
        name: "Erste Bank",
        image: erstebank,
        imageClasses: `max-h-40`,
        href: "https://www.erstebank.at/",
      },
    ],
  "Gold": [
    {
      name: "TU Wien CYSEC",
      image: tuwien,
      href: "https://tuwien.ac.at",
    },
    {
      name: "TU Graz ISEC",
      image: tugraz,
      href: "https://tugraz.at",
    },
    {
      name: "SBA-Research",
      image: sba,
      href: "https://sba-research.org",
    },
  ],
  "Silver": [
    {
      name: "Siemens",
      image: siemens,
      href: "https://siemens.at",
    },
    {
      name: "Bosch",
      image: bosch,
      href: "https://www.bosch.at/",
    },
    {
      name: "Johannes Kepler University Linz",
      image: jku,
      imageClasses: `max-h-8 md:max-h-24`,
      href: "https://www.jku.at",
    },
    {
      name: "FH St. Pölten",
      image: fhstp,
      imageClasses: `max-h-12 md:max-h-24`,
      href: "https://www.fhstp.ac.at",
    },
  ],
};
