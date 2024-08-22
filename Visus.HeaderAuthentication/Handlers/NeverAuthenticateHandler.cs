// <copyright file="NeverAuthenticateHandler.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using System.Threading.Tasks;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// A handler that always fails.
    /// </summary>
    internal class NeverAuthenticateHandler : IHeaderHandler {

        #region Public properties
        /// <inheritdoc />
        public string? AuthenticationType { get; set; }
        #endregion

        #region Public methods
        /// <inheritdoc />
        public Task<ClaimsPrincipal?> AuthenticateAsync(StringValues values)
            => Task.FromResult((ClaimsPrincipal?) null);
        #endregion
    }
}
