namespace Caseware.Collaborate.TokenExchange;

/// <summary>
/// Contract for the RFC 8693 Token Exchange operation.
/// Accepting this interface everywhere (rather than the concrete class) keeps
/// the endpoint and any future middleware testable without spinning up a real IdP.
/// </summary>
internal interface ITokenExchangeService
{
    /// <summary>
    /// Validates both the <paramref name="request"/>'s subject and actor tokens,
    /// enforces delegation policy, and issues a scoped Downstream Token containing
    /// the <c>act</c> claim that identifies the intermediary service.
    /// </summary>
    Task<ExchangeResult> ExchangeAsync(TokenExchangeRequest request, CancellationToken ct = default);
}
