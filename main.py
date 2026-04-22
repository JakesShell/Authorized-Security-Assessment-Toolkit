from port_scanner import scan_common_ports
from vulnerability_scanner import assess_web_headers
from remediation_advisor import print_remediation_guidance


def pause():
    input("\nPress Enter to return to the main menu...")


def main():
    while True:
        print("\nAuthorized Security Assessment Toolkit")
        print("For use only on systems you own or are explicitly authorized to assess.")
        print()
        print("1. Common Port Review")
        print("2. Web Security Header Review")
        print("3. Remediation Guidance")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            target = input("Enter a target hostname or IP address: ").strip()
            if not target:
                print("No target entered.")
                pause()
                continue

            results = scan_common_ports(target)
            if results:
                print("\nOpen ports discovered:")
                for item in results:
                    print(f"- Port {item['port']} ({item['service']})")
            else:
                print("\nNo open ports detected in the reviewed list.")

            pause()

        elif choice == "2":
            url = input("Enter the target URL: ").strip()
            if not url:
                print("No URL entered.")
                pause()
                continue

            findings = assess_web_headers(url)
            if findings:
                print_remediation_guidance(findings)

            pause()

        elif choice == "3":
            print_remediation_guidance()
            pause()

        elif choice == "4":
            print("Exiting toolkit.")
            break

        else:
            print("Invalid option selected. Please choose 1, 2, 3, or 4.")
            pause()


if __name__ == "__main__":
    main()
