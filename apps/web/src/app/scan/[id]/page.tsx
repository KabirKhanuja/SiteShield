import type { Metadata } from "next";
import { ScanReport } from "@/components/scan/scan-report";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";

export const metadata: Metadata = {
  title: "Scan report",
  // Reports are private to whoever has the link.
  robots: { index: false, follow: false },
};

export default async function ScanReportPage(props: PageProps<"/scan/[id]">) {
  const { id } = await props.params;
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-10 sm:px-6 lg:py-14">
        <ScanReport id={id} />
      </main>
      <SiteFooter />
    </>
  );
}
