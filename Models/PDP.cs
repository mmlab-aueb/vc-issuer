namespace vc_issuer.Models
{
    public abstract class PDP
    {
        public abstract string Issue(int endpointId, int clientId, ClientRequest clientRequest);
    }
}
