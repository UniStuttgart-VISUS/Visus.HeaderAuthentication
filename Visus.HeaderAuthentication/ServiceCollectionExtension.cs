// <copyright file="ServiceCollectionExtension.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using Visus.HeaderAuthentication.Configuration;
using Visus.HeaderAuthentication.Handlers;


namespace Visus.HeaderAuthentication {

    /// <summary>
    /// Extension methods for <see cref="IServiceCollection"/>.
    /// </summary>
    public static class ServiceCollectionExtension {

        #region Public methods
        /// <summary>
        /// Adds HTTP header-based authentication to the
        /// <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The service collection to add the
        /// authentication handler to.</param>
        /// <param name="defaultScheme">The name of the authentication scheme.
        /// </param>
        /// <param name="options">A callback for configuring the authentication
        /// details.</param>
        /// <returns><paramref name="services"/> with the services added.
        /// </returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="services"/> is <c>null</c>.</exception>
        public static IServiceCollection AddHeaderAuthentication(
                this IServiceCollection services,
                string defaultScheme,
                Action<HeaderAuthenticationOptions> options) {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            var builder = services.AddAuthentication(defaultScheme);
            builder.AddScheme<HeaderAuthenticationOptions,
                HeaderAuthenticationHandler>(defaultScheme, o => options(o));

            return services;
        }

        /// <summary>
        /// Adds HTTP header-based authentication to the
        /// <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The service collection to add the
        /// authentication handler to.</param>
        /// <param name="options">A callback for configuring the authentication
        /// details.</param>
        /// <returns><paramref name="services"/> with the services added.
        /// </returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="services"/> is <c>null</c>.</exception>
        public static IServiceCollection AddHeaderAuthentication(
                this IServiceCollection services,
                Action<HeaderAuthenticationOptions> options)
            => services.AddHeaderAuthentication(
                HeaderAuthenticationOptions.DefaultScheme,
                options);
        #endregion
    }
}
