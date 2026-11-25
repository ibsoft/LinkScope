1. Run clumsy.exe as Administrator.
2. Configure packet loss
3. In the Filtering field, enter:

`icmp and outbound and ip.DstAddr == 1.1.1.1`

4. Enable Drop, set the percentage to 30%, and click Start.

- This configuration affects outgoing ICMP packets to 1.1.1.1, leaving other traffic outside the filter unchanged.